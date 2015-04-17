class Listing < ActiveRecord::Base
	if Rails.env.development?
		has_attached_file :image, :styles => { :medium => "200x>", :thumb => "100x100>" }, :default_url => "missingimage.png"
		validates_attachment_content_type :image, :content_type => /\Aimage\/.*\Z/
	else
		has_attached_file :image, :styles => { :medium => "200x>", :thumb => "100x100>" }, :default_url => "missingimage.png", :storage => :dropbox,
    				:dropbox_credentials => Rails.root.join("config/dropbox.yml")
    	validates_attachment_content_type :image, :content_type => /\Aimage\/.*\Z/,
    	:path => ":style/:id_:filename"
    end

  #checks that name, description, and price fields are filled out
    validates :name, :description, :price, presence: true
  #numericality checks that what is inputed is a number
    validates :price, numericality: {greater_than: 0}
    validates_attachment_presence :image

    belongs_to :user
end

