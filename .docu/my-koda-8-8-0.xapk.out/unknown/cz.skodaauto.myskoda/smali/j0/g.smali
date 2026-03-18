.class public abstract Lj0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static volatile a:Lj0/c;


# direct methods
.method public static final a(Landroid/widget/RemoteViews;La7/e2;IILjava/lang/Integer;)I
    .locals 1

    .line 1
    const/4 v0, -0x1

    .line 2
    if-eq p2, v0, :cond_3

    .line 3
    .line 4
    if-eqz p4, :cond_0

    .line 5
    .line 6
    invoke-virtual {p4}, Ljava/lang/Integer;->intValue()I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    iget-object p1, p1, La7/e2;->g:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    :goto_0
    if-eq p1, v0, :cond_1

    .line 18
    .line 19
    const-string p4, "setInflatedId"

    .line 20
    .line 21
    invoke-virtual {p0, p2, p4, p1}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 22
    .line 23
    .line 24
    :cond_1
    if-eqz p3, :cond_2

    .line 25
    .line 26
    const-string p4, "setLayoutResource"

    .line 27
    .line 28
    invoke-virtual {p0, p2, p4, p3}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 29
    .line 30
    .line 31
    :cond_2
    const/4 p3, 0x0

    .line 32
    invoke-virtual {p0, p2, p3}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 33
    .line 34
    .line 35
    return p1

    .line 36
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 37
    .line 38
    const-string p1, "viewStubId must not be View.NO_ID"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0
.end method

.method public static final b(Ll70/q;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    new-instance p0, La8/r0;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :pswitch_0
    const p0, 0x7f120258

    .line 20
    .line 21
    .line 22
    return p0

    .line 23
    :pswitch_1
    const p0, 0x7f12025c

    .line 24
    .line 25
    .line 26
    return p0

    .line 27
    :pswitch_2
    const p0, 0x7f12024e

    .line 28
    .line 29
    .line 30
    return p0

    .line 31
    :pswitch_3
    const p0, 0x7f12024f

    .line 32
    .line 33
    .line 34
    return p0

    .line 35
    :pswitch_4
    const p0, 0x7f120251

    .line 36
    .line 37
    .line 38
    return p0

    .line 39
    :pswitch_5
    const p0, 0x7f120252

    .line 40
    .line 41
    .line 42
    return p0

    .line 43
    :pswitch_6
    const p0, 0x7f12024a

    .line 44
    .line 45
    .line 46
    return p0

    .line 47
    :pswitch_7
    const p0, 0x7f120249

    .line 48
    .line 49
    .line 50
    return p0

    .line 51
    :pswitch_8
    const p0, 0x7f12024b

    .line 52
    .line 53
    .line 54
    return p0

    .line 55
    :pswitch_9
    const p0, 0x7f12024c

    .line 56
    .line 57
    .line 58
    return p0

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
