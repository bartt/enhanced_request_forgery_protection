module CrumbTagsHelper

  # Renders 2 hidden tags named _crumb and _timestamp
  def crumb_tags
    timestamp = Time.now().to_i
    return "
#{tag(:input, {:type => 'hidden', :name => '_crumb', :value => issue_crumb(timestamp)})}
#{tag(:input, {:type => 'hidden', :name => '_timestamp', :value => timestamp})}"
  end

end
