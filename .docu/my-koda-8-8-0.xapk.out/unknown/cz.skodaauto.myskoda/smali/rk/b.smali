.class public final synthetic Lrk/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lqg/j;


# direct methods
.method public synthetic constructor <init>(Lqg/j;I)V
    .locals 0

    .line 1
    iput p2, p0, Lrk/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lrk/b;->e:Lqg/j;

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
    .locals 8

    .line 1
    iget v0, p0, Lrk/b;->d:I

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
    move-object v5, p2

    .line 33
    check-cast v5, Ll2/t;

    .line 34
    .line 35
    invoke-virtual {v5, p3, p1}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-eqz p1, :cond_1

    .line 40
    .line 41
    const p1, 0x7f120a8f

    .line 42
    .line 43
    .line 44
    invoke-static {v5, p1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    iget-object p0, p0, Lrk/b;->e:Lqg/j;

    .line 49
    .line 50
    iget-object p0, p0, Lqg/j;->h:Lqg/b;

    .line 51
    .line 52
    iget-object v3, p0, Lqg/b;->a:Ljava/lang/String;

    .line 53
    .line 54
    iget-boolean v6, p0, Lqg/b;->b:Z

    .line 55
    .line 56
    const/4 v4, 0x0

    .line 57
    const v0, 0x36006

    .line 58
    .line 59
    .line 60
    const-string v1, "followUp_"

    .line 61
    .line 62
    const/4 v7, 0x0

    .line 63
    invoke-static/range {v0 .. v7}, Lrk/a;->c(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;ZZ)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 68
    .line 69
    .line 70
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 71
    .line 72
    return-object p0

    .line 73
    :pswitch_0
    const-string v0, "$this$item"

    .line 74
    .line 75
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    and-int/lit8 p1, p3, 0x11

    .line 79
    .line 80
    const/16 v0, 0x10

    .line 81
    .line 82
    const/4 v1, 0x1

    .line 83
    if-eq p1, v0, :cond_2

    .line 84
    .line 85
    move p1, v1

    .line 86
    goto :goto_2

    .line 87
    :cond_2
    const/4 p1, 0x0

    .line 88
    :goto_2
    and-int/2addr p3, v1

    .line 89
    move-object v5, p2

    .line 90
    check-cast v5, Ll2/t;

    .line 91
    .line 92
    invoke-virtual {v5, p3, p1}, Ll2/t;->O(IZ)Z

    .line 93
    .line 94
    .line 95
    move-result p1

    .line 96
    if-eqz p1, :cond_3

    .line 97
    .line 98
    iget-object p0, p0, Lrk/b;->e:Lqg/j;

    .line 99
    .line 100
    iget-object p0, p0, Lqg/j;->h:Lqg/b;

    .line 101
    .line 102
    iget-object v2, p0, Lqg/b;->d:Ljava/lang/String;

    .line 103
    .line 104
    iget-object v3, p0, Lqg/b;->a:Ljava/lang/String;

    .line 105
    .line 106
    iget-boolean v6, p0, Lqg/b;->b:Z

    .line 107
    .line 108
    iget-object v4, p0, Lqg/b;->c:Ljava/lang/String;

    .line 109
    .line 110
    const/16 v0, 0x6006

    .line 111
    .line 112
    const-string v1, "active_"

    .line 113
    .line 114
    const/4 v7, 0x1

    .line 115
    invoke-static/range {v0 .. v7}, Lrk/a;->c(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;ZZ)V

    .line 116
    .line 117
    .line 118
    goto :goto_3

    .line 119
    :cond_3
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 120
    .line 121
    .line 122
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 123
    .line 124
    return-object p0

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
