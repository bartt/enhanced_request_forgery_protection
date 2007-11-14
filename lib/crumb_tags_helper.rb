module CrumbTagsHelper #:doc:

  # +crumb_tags+ renders 2 hidden tags named +_crumb+ and +_timestamp+
  # that can be verified by action controller filter +verify_crumb+ to
  # ensure that the form submission came from a trusted source.
  #
  # The value of +_crumb+ is set by +issue_crumb+.
  def crumb_tags
    timestamp = Time.now().to_i
    return "
#{tag(:input, {:type => 'hidden', :name => '_crumb', :value => issue_crumb(timestamp)})}
#{tag(:input, {:type => 'hidden', :name => '_timestamp', :value => timestamp})}"
  end

end
