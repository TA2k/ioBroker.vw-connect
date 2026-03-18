.class public final Lkn/k;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ll2/b1;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lkn/c0;Lk1/b;Lt4/c;Ll2/b1;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lkn/k;->f:I

    .line 1
    iput-object p1, p0, Lkn/k;->h:Ljava/lang/Object;

    iput-object p2, p0, Lkn/k;->i:Ljava/lang/Object;

    iput-object p3, p0, Lkn/k;->j:Ljava/lang/Object;

    iput-object p4, p0, Lkn/k;->g:Ll2/b1;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public synthetic constructor <init>(Llx0/e;Ll2/b1;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p5, p0, Lkn/k;->f:I

    iput-object p1, p0, Lkn/k;->h:Ljava/lang/Object;

    iput-object p2, p0, Lkn/k;->g:Ll2/b1;

    iput-object p3, p0, Lkn/k;->i:Ljava/lang/Object;

    iput-object p4, p0, Lkn/k;->j:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lkn/k;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ld3/b;

    .line 7
    .line 8
    iget-wide v0, p1, Ld3/b;->a:J

    .line 9
    .line 10
    iget-object p1, p0, Lkn/k;->g:Ll2/b1;

    .line 11
    .line 12
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-interface {p1, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    iget-object p1, p0, Lkn/k;->j:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p1, Ll2/b1;

    .line 20
    .line 21
    new-instance v2, Li1/b;

    .line 22
    .line 23
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 24
    .line 25
    .line 26
    iget-object v3, p0, Lkn/k;->i:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v3, Lvy0/b0;

    .line 29
    .line 30
    new-instance v4, Lx21/d;

    .line 31
    .line 32
    const/4 v5, 0x1

    .line 33
    const/4 v6, 0x0

    .line 34
    invoke-direct {v4, v2, v6, v5}, Lx21/d;-><init>(Li1/b;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 v5, 0x3

    .line 38
    invoke-static {v3, v6, v6, v4, v5}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    invoke-interface {p1, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Lkn/k;->h:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Lay0/k;

    .line 47
    .line 48
    new-instance p1, Ld3/b;

    .line 49
    .line 50
    invoke-direct {p1, v0, v1}, Ld3/b;-><init>(J)V

    .line 51
    .line 52
    .line 53
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_0
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 60
    .line 61
    const-string v0, "$this$DisposableEffect"

    .line 62
    .line 63
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    iget-object p1, p0, Lkn/k;->h:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p1, Lay0/a;

    .line 69
    .line 70
    iget-object v0, p0, Lkn/k;->i:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v0, Ll2/b1;

    .line 73
    .line 74
    iget-object v1, p0, Lkn/k;->j:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v1, Lvy0/b0;

    .line 77
    .line 78
    new-instance v2, Lx21/e;

    .line 79
    .line 80
    iget-object p0, p0, Lkn/k;->g:Ll2/b1;

    .line 81
    .line 82
    invoke-direct {v2, p1, p0, v0, v1}, Lx21/e;-><init>(Lay0/a;Ll2/b1;Ll2/b1;Lvy0/b0;)V

    .line 83
    .line 84
    .line 85
    return-object v2

    .line 86
    :pswitch_1
    check-cast p1, Ld3/b;

    .line 87
    .line 88
    iget-wide v0, p1, Ld3/b;->a:J

    .line 89
    .line 90
    iget-object p1, p0, Lkn/k;->h:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast p1, Lkn/c0;

    .line 93
    .line 94
    iget-object v2, p1, Lkn/c0;->q:Lh6/j;

    .line 95
    .line 96
    invoke-virtual {v2}, Lh6/j;->g()V

    .line 97
    .line 98
    .line 99
    const v3, 0x7f7fffff    # Float.MAX_VALUE

    .line 100
    .line 101
    .line 102
    invoke-static {v3, v3}, Lkp/g9;->a(FF)J

    .line 103
    .line 104
    .line 105
    move-result-wide v3

    .line 106
    invoke-virtual {v2, v3, v4}, Lh6/j;->e(J)J

    .line 107
    .line 108
    .line 109
    move-result-wide v2

    .line 110
    invoke-static {v2, v3}, Lt4/q;->c(J)F

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    iput v2, p1, Lkn/c0;->p:F

    .line 115
    .line 116
    invoke-static {v0, v1}, Ld3/b;->f(J)F

    .line 117
    .line 118
    .line 119
    move-result p1

    .line 120
    iget-object v2, p0, Lkn/k;->i:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v2, Lk1/q1;

    .line 123
    .line 124
    iget-object v3, p0, Lkn/k;->j:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast v3, Lt4/c;

    .line 127
    .line 128
    invoke-interface {v2, v3}, Lk1/q1;->b(Lt4/c;)I

    .line 129
    .line 130
    .line 131
    move-result v2

    .line 132
    int-to-float v2, v2

    .line 133
    sub-float/2addr p1, v2

    .line 134
    const/4 v2, 0x1

    .line 135
    invoke-static {v0, v1, v2, p1}, Ld3/b;->a(JIF)J

    .line 136
    .line 137
    .line 138
    move-result-wide v0

    .line 139
    new-instance p1, Ld3/b;

    .line 140
    .line 141
    invoke-direct {p1, v0, v1}, Ld3/b;-><init>(J)V

    .line 142
    .line 143
    .line 144
    iget-object p0, p0, Lkn/k;->g:Ll2/b1;

    .line 145
    .line 146
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    return-object p0

    .line 152
    nop

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
