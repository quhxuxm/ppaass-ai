package com.ppaass.ai.agent;

import android.content.Context;
import android.view.View;
import android.widget.ScrollView;

// 规则列表需要“内容少时自然收缩，内容多时内部滚动”，所以只限制最大高度。
final class MaxHeightScrollView extends ScrollView {
    private final int maxHeightPx;

    MaxHeightScrollView(Context context, int maxHeightPx) {
        super(context);
        this.maxHeightPx = maxHeightPx;
    }

    @Override
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int cappedHeightSpec = View.MeasureSpec.makeMeasureSpec(
                maxHeightPx,
                View.MeasureSpec.AT_MOST);
        super.onMeasure(widthMeasureSpec, cappedHeightSpec);
    }
}
