.class public final Lbp0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lij0/a;

.field public final b:Lcs0/l;


# direct methods
.method public constructor <init>(Lcs0/l;Lij0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lbp0/b;->a:Lij0/a;

    .line 5
    .line 6
    iput-object p1, p0, Lbp0/b;->b:Lcs0/l;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;Lap0/h;Landroidx/core/app/x;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p4, Lbp0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lbp0/a;

    .line 7
    .line 8
    iget v1, v0, Lbp0/a;->k:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lbp0/a;->k:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lbp0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Lbp0/a;-><init>(Lbp0/b;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Lbp0/a;->i:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lbp0/a;->k:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-wide p0, v0, Lbp0/a;->h:D

    .line 37
    .line 38
    iget-object p2, v0, Lbp0/a;->g:Landroid/widget/RemoteViews;

    .line 39
    .line 40
    iget-object p3, v0, Lbp0/a;->f:Landroid/widget/RemoteViews;

    .line 41
    .line 42
    iget-object v1, v0, Lbp0/a;->e:Landroidx/core/app/x;

    .line 43
    .line 44
    iget-object v0, v0, Lbp0/a;->d:Lap0/h;

    .line 45
    .line 46
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    new-instance p4, Landroid/widget/RemoteViews;

    .line 62
    .line 63
    invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    const v2, 0x7f0d02e0

    .line 68
    .line 69
    .line 70
    invoke-direct {p4, p1, v2}, Landroid/widget/RemoteViews;-><init>(Ljava/lang/String;I)V

    .line 71
    .line 72
    .line 73
    iget-wide v4, p2, Lap0/h;->b:D

    .line 74
    .line 75
    iput-object p2, v0, Lbp0/a;->d:Lap0/h;

    .line 76
    .line 77
    iput-object p3, v0, Lbp0/a;->e:Landroidx/core/app/x;

    .line 78
    .line 79
    iput-object p4, v0, Lbp0/a;->f:Landroid/widget/RemoteViews;

    .line 80
    .line 81
    iput-object p4, v0, Lbp0/a;->g:Landroid/widget/RemoteViews;

    .line 82
    .line 83
    iput-wide v4, v0, Lbp0/a;->h:D

    .line 84
    .line 85
    iput v3, v0, Lbp0/a;->k:I

    .line 86
    .line 87
    iget-object p0, p0, Lbp0/b;->b:Lcs0/l;

    .line 88
    .line 89
    invoke-virtual {p0, v0}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    if-ne p0, v1, :cond_3

    .line 94
    .line 95
    return-object v1

    .line 96
    :cond_3
    move-object v0, p2

    .line 97
    move-object v1, p3

    .line 98
    move-object p2, p4

    .line 99
    move-object p3, p2

    .line 100
    move-object p4, p0

    .line 101
    move-wide p0, v4

    .line 102
    :goto_1
    check-cast p4, Lqr0/s;

    .line 103
    .line 104
    sget-object v2, Lqr0/e;->e:Lqr0/e;

    .line 105
    .line 106
    invoke-static {p0, p1, p4, v2}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    iget-object p1, v0, Lap0/h;->a:Lqr0/l;

    .line 111
    .line 112
    invoke-static {p1}, Lkp/l6;->a(Lqr0/l;)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    new-instance p4, Ljava/lang/StringBuilder;

    .line 117
    .line 118
    invoke-direct {p4}, Ljava/lang/StringBuilder;-><init>()V

    .line 119
    .line 120
    .line 121
    invoke-virtual {p4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    const-string p1, " / "

    .line 125
    .line 126
    invoke-virtual {p4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    invoke-virtual {p4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {p4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    const p1, 0x7f0a0235

    .line 137
    .line 138
    .line 139
    invoke-virtual {p2, p1, p0}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 140
    .line 141
    .line 142
    new-instance p0, Landroidx/core/app/z;

    .line 143
    .line 144
    invoke-direct {p0}, Landroidx/core/app/a0;-><init>()V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v1, p0}, Landroidx/core/app/x;->f(Landroidx/core/app/a0;)V

    .line 148
    .line 149
    .line 150
    iput-object p3, v1, Landroidx/core/app/x;->s:Landroid/widget/RemoteViews;

    .line 151
    .line 152
    const/16 p0, 0x10

    .line 153
    .line 154
    invoke-virtual {v1, p0, v3}, Landroidx/core/app/x;->d(IZ)V

    .line 155
    .line 156
    .line 157
    sget p0, Lmy0/c;->g:I

    .line 158
    .line 159
    const/16 p0, 0x1e

    .line 160
    .line 161
    sget-object p1, Lmy0/e;->i:Lmy0/e;

    .line 162
    .line 163
    invoke-static {p0, p1}, Lmy0/h;->s(ILmy0/e;)J

    .line 164
    .line 165
    .line 166
    move-result-wide p0

    .line 167
    invoke-static {p0, p1}, Lmy0/c;->e(J)J

    .line 168
    .line 169
    .line 170
    move-result-wide p0

    .line 171
    iput-wide p0, v1, Landroidx/core/app/x;->v:J

    .line 172
    .line 173
    return-object v1
.end method
