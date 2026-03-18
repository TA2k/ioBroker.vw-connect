.class public final Lba0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lba0/g;


# direct methods
.method public synthetic constructor <init>(Lba0/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Lba0/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lba0/e;->e:Lba0/g;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget p2, p0, Lba0/e;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/d;

    .line 9
    .line 10
    iget-object p0, p0, Lba0/e;->e:Lba0/g;

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    move-object v0, p1

    .line 19
    check-cast v0, Lba0/f;

    .line 20
    .line 21
    const/4 v5, 0x0

    .line 22
    const/16 v6, 0x2f

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    invoke-static/range {v0 .. v6}, Lba0/f;->a(Lba0/f;Ljava/lang/String;Ljava/lang/String;ZZLql0/g;I)Lba0/f;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    instance-of p2, p1, Lne0/e;

    .line 37
    .line 38
    if-eqz p2, :cond_1

    .line 39
    .line 40
    iget-object p1, p0, Lba0/g;->m:Lz90/l;

    .line 41
    .line 42
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lba0/g;->i:Ltr0/b;

    .line 46
    .line 47
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    instance-of p2, p1, Lne0/c;

    .line 52
    .line 53
    if-eqz p2, :cond_2

    .line 54
    .line 55
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    move-object v0, p2

    .line 60
    check-cast v0, Lba0/f;

    .line 61
    .line 62
    check-cast p1, Lne0/c;

    .line 63
    .line 64
    iget-object p2, p0, Lba0/g;->l:Lij0/a;

    .line 65
    .line 66
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    const/16 v6, 0x1f

    .line 71
    .line 72
    const/4 v1, 0x0

    .line 73
    const/4 v2, 0x0

    .line 74
    const/4 v3, 0x0

    .line 75
    const/4 v4, 0x0

    .line 76
    invoke-static/range {v0 .. v6}, Lba0/f;->a(Lba0/f;Ljava/lang/String;Ljava/lang/String;ZZLql0/g;I)Lba0/f;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 81
    .line 82
    .line 83
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    return-object p0

    .line 86
    :cond_2
    new-instance p0, La8/r0;

    .line 87
    .line 88
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 89
    .line 90
    .line 91
    throw p0

    .line 92
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 93
    .line 94
    instance-of p2, p1, Lne0/e;

    .line 95
    .line 96
    if-eqz p2, :cond_3

    .line 97
    .line 98
    iget-object p0, p0, Lba0/e;->e:Lba0/g;

    .line 99
    .line 100
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 101
    .line 102
    .line 103
    move-result-object p2

    .line 104
    move-object v0, p2

    .line 105
    check-cast v0, Lba0/f;

    .line 106
    .line 107
    check-cast p1, Lne0/e;

    .line 108
    .line 109
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast p1, Lss0/k;

    .line 112
    .line 113
    iget-object p1, p1, Lss0/k;->e:Ljava/lang/String;

    .line 114
    .line 115
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 116
    .line 117
    .line 118
    move-result-object p2

    .line 119
    const-string v1, "now(...)"

    .line 120
    .line 121
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-static {p2}, Lvo/a;->g(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p2

    .line 128
    const-string v1, " | "

    .line 129
    .line 130
    invoke-static {p1, v1, p2}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    const/4 v5, 0x0

    .line 135
    const/16 v6, 0x3d

    .line 136
    .line 137
    const/4 v1, 0x0

    .line 138
    const/4 v3, 0x0

    .line 139
    const/4 v4, 0x0

    .line 140
    invoke-static/range {v0 .. v6}, Lba0/f;->a(Lba0/f;Ljava/lang/String;Ljava/lang/String;ZZLql0/g;I)Lba0/f;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 145
    .line 146
    .line 147
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 148
    .line 149
    return-object p0

    .line 150
    nop

    .line 151
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
