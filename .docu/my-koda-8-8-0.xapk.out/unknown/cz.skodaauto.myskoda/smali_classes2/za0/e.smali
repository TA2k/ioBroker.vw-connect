.class public final synthetic Lza0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lya0/a;

.field public final synthetic f:Lza0/q;


# direct methods
.method public synthetic constructor <init>(Lya0/a;Lza0/q;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lza0/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lza0/e;->e:Lya0/a;

    iput-object p2, p0, Lza0/e;->f:Lza0/q;

    return-void
.end method

.method public synthetic constructor <init>(Lza0/q;Lya0/a;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lza0/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lza0/e;->f:Lza0/q;

    iput-object p2, p0, Lza0/e;->e:Lya0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lza0/e;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    move-object v9, p1

    .line 25
    check-cast v9, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v9, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    sget-object p1, Ly6/o;->a:Ly6/o;

    .line 34
    .line 35
    invoke-static {p1}, Lkp/p7;->b(Ly6/q;)Ly6/q;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    iget-object p1, p0, Lza0/e;->e:Lya0/a;

    .line 40
    .line 41
    iget-object v3, p1, Lya0/a;->a:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v4, p1, Lya0/a;->b:Ljava/lang/String;

    .line 44
    .line 45
    iget-object v5, p1, Lya0/a;->c:Ljava/lang/String;

    .line 46
    .line 47
    iget-boolean v7, p1, Lya0/a;->e:Z

    .line 48
    .line 49
    iget-object v6, p1, Lya0/a;->g:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v8, p1, Lya0/a;->d:Ljava/lang/Boolean;

    .line 52
    .line 53
    const/high16 v10, 0x1000000

    .line 54
    .line 55
    iget-object v1, p0, Lza0/e;->f:Lza0/q;

    .line 56
    .line 57
    invoke-virtual/range {v1 .. v10}, Lza0/q;->e(Ly6/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Boolean;Ll2/o;I)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_1
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 62
    .line 63
    .line 64
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    return-object p0

    .line 67
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 68
    .line 69
    const/4 v1, 0x2

    .line 70
    const/4 v2, 0x1

    .line 71
    if-eq v0, v1, :cond_2

    .line 72
    .line 73
    move v0, v2

    .line 74
    goto :goto_2

    .line 75
    :cond_2
    const/4 v0, 0x0

    .line 76
    :goto_2
    and-int/2addr p2, v2

    .line 77
    check-cast p1, Ll2/t;

    .line 78
    .line 79
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 80
    .line 81
    .line 82
    move-result p2

    .line 83
    if-eqz p2, :cond_3

    .line 84
    .line 85
    sget-object p2, Ly6/o;->a:Ly6/o;

    .line 86
    .line 87
    invoke-static {p2}, Lkp/p7;->e(Ly6/q;)Ly6/q;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    invoke-static {v0}, Lkp/p7;->f(Ly6/q;)Ly6/q;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    const/16 v1, 0x40

    .line 96
    .line 97
    iget-object v2, p0, Lza0/e;->f:Lza0/q;

    .line 98
    .line 99
    invoke-virtual {v2, v0, p1, v1}, Lza0/q;->g(Ly6/q;Ll2/o;I)V

    .line 100
    .line 101
    .line 102
    invoke-static {p2}, Lkp/p7;->b(Ly6/q;)Ly6/q;

    .line 103
    .line 104
    .line 105
    move-result-object p2

    .line 106
    new-instance v0, Lza0/e;

    .line 107
    .line 108
    iget-object p0, p0, Lza0/e;->e:Lya0/a;

    .line 109
    .line 110
    invoke-direct {v0, p0, v2}, Lza0/e;-><init>(Lya0/a;Lza0/q;)V

    .line 111
    .line 112
    .line 113
    const p0, 0x165a09f4

    .line 114
    .line 115
    .line 116
    invoke-static {p0, p1, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    const/16 v0, 0x180

    .line 121
    .line 122
    sget-object v1, Lf7/c;->f:Lf7/c;

    .line 123
    .line 124
    invoke-static {p2, v1, p0, p1, v0}, Lkp/j7;->a(Ly6/q;Lf7/c;Lt2/b;Ll2/o;I)V

    .line 125
    .line 126
    .line 127
    goto :goto_3

    .line 128
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 129
    .line 130
    .line 131
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    return-object p0

    .line 134
    nop

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
