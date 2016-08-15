#
# Author:: Seth Chisamore (<schisamo@chef.io>)
# Copyright:: Copyright 2011-2016, Chef Software Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require "chef/mixin/properties"
require "chef/mixin/property_types"
require "chef/property/array_property"

class Chef
  module Mixin
    module Securable

      include Chef::Mixin::Properties

      property :owner, Chef::Config[:user_valid_regex]
      alias :user :owner
      alias :user= :owner=
      property :group, Chef::Config[:group_valid_regex]
      property :mode, [ String, Integer ], callbacks: {
        "not in valid numeric range" => lambda do |m|
          if m.kind_of?(String)
            m =~ /^0/ || m = "0#{m}"
          end

          # Windows does not support the sticky or setuid bits
          if Chef::Platform.windows?
            Integer(m) <= 0777 && Integer(m) >= 0
          else
            Integer(m) <= 07777 && Integer(m) >= 0
          end
        end,
      }

      # === rights_attribute
      # "meta-method" for dynamically creating rights attributes on resources.
      #
      # Multiple rights attributes can be declared. This enables resources to
      # have multiple rights attributes with separate runtime states.
      #
      # For example, +Chef::Resource::RemoteDirectory+ supports different
      # rights on the directories and files by declaring separate rights
      # attributes for each (rights and files_rights).
      #
      # ==== User Level API
      # Given a resource that calls
      #
      #   rights_attribute(:rights)
      #
      # Then the resource DSL could be used like this:
      #
      #   rights :read, ["Administrators","Everyone"]
      #   rights :deny, "Pinky"
      #   rights :full_control, "Users", :applies_to_children => true
      #   rights :write, "John Keiser", :applies_to_children => :containers_only, :applies_to_self => false, :one_level_deep => true
      #
      # ==== Internal Data Structure
      # rights attributes support multiple right declarations
      # in a single resource block--the data will be merged
      # into a single internal hash.
      #
      # The internal representation is a hash with the following keys:
      #
      # * `:permissions`: Integer of Windows permissions flags, 1..2^32
      # or one of `[:full_control, :modify, :read_execute, :read, :write]`
      # * `:principals`:  String or Array of Strings represnting usernames on
      # the system.
      # * `:applies_to_children` (optional): Boolean
      # * `:applies_to_self` (optional): Boolean
      # * `:one_level_deep` (optional): Boolean
      #
      def rights_attribute(name)
        property name, WindowsRights
      end

      class WindowsRightsValue < Property
        include Chef::Mixin::Properties

        # Single permission can be true, false,
        PermissionValue = property_type(
          is: [ :full_control, :modify, :read_execute, :read, :write ],
          coerce: { |v| v.is_a?(Integer) ? v : v.to_sym },
          callbacks: {
            "permissions flags must be positive and <= 32 bits" => proc do |permission|
              if permission.is_a?(Integer)
                permission < 0 || permission > 1 << 32
              else
                true
              end
            end,
          },
        )

        Permissions = ArrayProperty[PermissionValue]
        Principals = ArrayProperty[String]
        AppliesToChildren = property_type [ true, false, :containers_only, :objects_only ]

        def call(resource, *args)
          if args.size >= 2
            permissions, principals, args_hash = *args
            args_hash ||= {}
            args_hash[:permissions] = permissions
            args_hash[:principals] = principals
            super(resource, args_hash)
          else
            super
          end
        end

        def coerce(resource, value)
          value[:permissions] = Permissions.transform(value[:permissions])
          value[:principals] = Principals.transform(value[:principals])
          value[:applies_to_children] = AppliesToChildren.transform(value[:applies_to_children])
          value[:applies_to_self] = Boolean.transform(value[:applies_to_self])
          value[:one_level_deep] = Boolean.transform(value[:one_level_deep])
          value
        end

        def validate(resource, value)
          super
          raise ValidationError, ":permissions is required" unless value[:permissions]
          raise ValidationError, ":principals is required" unless value[:principals]
        end
      end

      WindowsRights = ArrayProperty.new(element_type: WindowsRightsValue, append: true)

      #==WindowsSecurableAttributes
      # Defines #inherits to describe Windows file security ACLs on the
      # including class
      module WindowsSecurableAttributes

        def inherits(arg = nil)
          set_or_return(
            :inherits,
            arg,
            :kind_of => [ TrueClass, FalseClass ]
          )
        end
      end

      if RUBY_PLATFORM =~ /mswin|mingw|windows/
        include WindowsSecurableAttributes
      end

      # Callback that fires when included; will extend the including class
      # with WindowsMacros and define #rights and #deny_rights on it.
      def self.included(including_class)
        if RUBY_PLATFORM =~ /mswin|mingw|windows/
          including_class.extend(WindowsMacros)
          # create a default 'rights' attribute
          including_class.rights_attribute(:rights)
          including_class.rights_attribute(:deny_rights)
        end
      end

    end
  end
end
