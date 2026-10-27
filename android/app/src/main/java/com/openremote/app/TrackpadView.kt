package com.openremote.app

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.util.AttributeSet
import android.view.View
import kotlin.math.abs

/**
 * The big swipe surface of the classic Android TV remote: swipe gestures fire
 * D-pad events, a tap fires OK. The center dot follows the finger while
 * touching and returns to the middle on release (1:1 with the original UI).
 */
class TrackpadView(context: Context, attrs: AttributeSet?) : View(context, attrs) {

    enum class Direction { UP, DOWN, LEFT, RIGHT }

    interface Listener {
        fun onDirection(direction: Direction)
        fun onTap()
    }

    var listener: Listener? = null

    private val dotPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFFDADCE0.toInt()
        style = Paint.Style.FILL
    }

    private var dotX = 0f
    private var dotY = 0f
    private var originX = 0f
    private var originY = 0f
    private var moved = false

    private val threshold: Float
        get() = width / 4.2f

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        resetDot()
    }

    private fun resetDot() {
        dotX = width / 2f
        dotY = height / 2f
    }

    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(event: android.view.MotionEvent): Boolean {
        when (event.actionMasked) {
            android.view.MotionEvent.ACTION_DOWN -> {
                originX = event.x
                originY = event.y
                moved = false
                dotX = event.x
                dotY = event.y
                invalidate()
            }
            android.view.MotionEvent.ACTION_MOVE -> {
                dotX = event.x
                dotY = event.y
                val dx = event.x - originX
                val dy = event.y - originY
                if (abs(dx) > threshold || abs(dy) > threshold) {
                    val direction = if (abs(dx) > abs(dy)) {
                        if (dx > 0) Direction.RIGHT else Direction.LEFT
                    } else {
                        if (dy > 0) Direction.DOWN else Direction.UP
                    }
                    listener?.onDirection(direction)
                    originX = event.x
                    originY = event.y
                    moved = true
                }
                invalidate()
            }
            android.view.MotionEvent.ACTION_UP, android.view.MotionEvent.ACTION_CANCEL -> {
                resetDot()
                invalidate()
                if (!moved && event.actionMasked == android.view.MotionEvent.ACTION_UP) {
                    listener?.onTap()
                }
            }
        }
        return true
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val radius = resources.displayMetrics.density * 20f
        canvas.drawCircle(dotX, dotY, radius, dotPaint)
    }
}
