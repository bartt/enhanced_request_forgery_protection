# Include hook code here

ActionController::Base.send(:include, Crumblr)
ActionView::Base.send(:include, CrumbTagsHelper)
