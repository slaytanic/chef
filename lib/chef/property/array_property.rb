#
# Author:: John Keiser (<jkeiser@chef.io>)
# Copyright:: Copyright 2016-2016, Chef Software Inc.
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

require "chef/property"

class Chef
  class Property
    #
    # Property allowing a freeform array setter syntax:
    #
    #   ```
    #   my_property 1, 2, 3
    #      # ==> [ 1, 2, 3 ]
    #   ```
    #
    # Also allows for an element type, and coerces and validates using said type.
    #
    class ArrayProperty < Property
      #
      # Creates a new array property type.
      #
      # Has the same arguments as Property, plus:
      #
      # @option options [Property] :element_type The element type of the property.
      # @option options [Property] :append `true` to have each call to
      #   `my_property x` append x to the array value. `my_property = x` will
      #   still wipe out any existing values. Defaults to `false`.
      #
      def initialize(**options)
        super
      end

      #
      # The element type.
      #
      # @return [Property] The element type of the property.
      #
      def element_type
        options[:element_type]
      end

      #
      # Whether to append to the array or set it.
      #
      # @return [Boolean] `true` if calls to `my_property x` will append x to the array;
      #   `false` if it will set the array to `[ x ]`
      #
      def append?
        options[:append]
      end

      #
      # Creates a new array property type with the given element type.
      #
      # @param element_type [Property] The element type of the array.
      # @param options [Hash] Other options to the property type (same as options to `property_type`).
      #
      # @return [ArrayProperty] The array property type.
      #
      # @example
      #     ArrayProperty[String, regex: /abc/] = array of strings matching abc
      #
      # @example
      #     ArrayProperty[String, Integer] = array of either strings or integers
      #
      # @example
      #     ArrayProperty[regex: /abc/] = array of strings matching abc
      #
      def self.[](*element_type, **options)
        element_type = element_type[0] if element_type.size == 1
        case element_type
        when []
          element_type = nil
        when Property
          element_type = element_type.derive(**options) if options.any?
        else
          options[:is] = element_type
          element_type = Property.derive(**options)
        end
        ArrayProperty.new(element_type: element_type)
      end

      # allows syntax "myproperty :a, :b, :c" == `myproperty [ :a, :b, :c ]`
      def call(resource, *values)
        super(resource, values.flatten)
      end

      # coerces non-arrays to arrays; coerces array elements using element_type.coerce
      def coerce(resource, value)
        value = Array(value)
        value = value.map { |element| element_type.coerce(resource, element) } if element_type
        super(resource, value)
      end

      # validates the elements of the array using element_type.validate
      def validate(resource, value)
        super
        value.each { |element| element_type.validate(resource, element) } if element_type
      end
    end
  end
end
