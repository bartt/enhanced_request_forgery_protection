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

  # +crumb_params+ returns a hash of query parameters to be used by
  # +url_for+ and family. Use +crumb_params+ if you can't use POST and
  # have to use GET submission.
  #
  # The value of +_crumb+ is set by +issue_crumb+.
  def crumb_params
    timestamp = Time.now().to_i
    return { '_crumb' => issue_crumb(timestamp), '_timestamp' => timestamp}
  end
end
