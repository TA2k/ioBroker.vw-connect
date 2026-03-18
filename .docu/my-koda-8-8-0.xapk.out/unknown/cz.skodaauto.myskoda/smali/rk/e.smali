.class public final synthetic Lrk/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lqg/k;


# direct methods
.method public synthetic constructor <init>(Lqg/k;I)V
    .locals 0

    .line 1
    iput p2, p0, Lrk/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lrk/e;->e:Lqg/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lrk/e;->d:I

    .line 2
    .line 3
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 4
    .line 5
    check-cast p2, Ll2/o;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    const-string v0, "$this$item"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 p1, p3, 0x11

    .line 22
    .line 23
    const/16 v0, 0x10

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    if-eq p1, v0, :cond_0

    .line 27
    .line 28
    move p1, v1

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 p1, 0x0

    .line 31
    :goto_0
    and-int/2addr p3, v1

    .line 32
    move-object v3, p2

    .line 33
    check-cast v3, Ll2/t;

    .line 34
    .line 35
    invoke-virtual {v3, p3, p1}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-eqz p1, :cond_1

    .line 40
    .line 41
    iget-object p0, p0, Lrk/e;->e:Lqg/k;

    .line 42
    .line 43
    iget-object p0, p0, Lqg/k;->d:Lqg/i;

    .line 44
    .line 45
    iget-object v0, p0, Lqg/i;->d:Ljava/lang/String;

    .line 46
    .line 47
    const/16 v4, 0x180

    .line 48
    .line 49
    const/4 v5, 0x2

    .line 50
    const/4 v1, 0x0

    .line 51
    sget-object v2, Lrk/a;->g:Lt2/b;

    .line 52
    .line 53
    invoke-static/range {v0 .. v5}, Lzb/b;->e(Ljava/lang/String;Lx2/s;Lt2/b;Ll2/o;II)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 58
    .line 59
    .line 60
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_0
    const-string v0, "$this$item"

    .line 64
    .line 65
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    and-int/lit8 p1, p3, 0x11

    .line 69
    .line 70
    const/16 v0, 0x10

    .line 71
    .line 72
    const/4 v1, 0x1

    .line 73
    if-eq p1, v0, :cond_2

    .line 74
    .line 75
    move p1, v1

    .line 76
    goto :goto_2

    .line 77
    :cond_2
    const/4 p1, 0x0

    .line 78
    :goto_2
    and-int/2addr p3, v1

    .line 79
    move-object v3, p2

    .line 80
    check-cast v3, Ll2/t;

    .line 81
    .line 82
    invoke-virtual {v3, p3, p1}, Ll2/t;->O(IZ)Z

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    if-eqz p1, :cond_3

    .line 87
    .line 88
    iget-object p0, p0, Lrk/e;->e:Lqg/k;

    .line 89
    .line 90
    iget-object p0, p0, Lqg/k;->d:Lqg/i;

    .line 91
    .line 92
    iget-object v0, p0, Lqg/i;->f:Ljava/lang/String;

    .line 93
    .line 94
    const/16 v4, 0x180

    .line 95
    .line 96
    const/4 v5, 0x2

    .line 97
    const/4 v1, 0x0

    .line 98
    sget-object v2, Lrk/a;->f:Lt2/b;

    .line 99
    .line 100
    invoke-static/range {v0 .. v5}, Lzb/b;->d(Ljava/lang/String;Lx2/s;Lt2/b;Ll2/o;II)V

    .line 101
    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_3
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 105
    .line 106
    .line 107
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    return-object p0

    .line 110
    nop

    .line 111
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
