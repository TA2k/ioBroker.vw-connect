.class public final Lq40/j;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lo40/l;


# direct methods
.method public constructor <init>(Lo40/j;Lij0/a;Lo40/l;)V
    .locals 11

    .line 1
    new-instance v0, Lq40/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lq40/i;-><init>(Lql0/g;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p3, p0, Lq40/j;->h:Lo40/l;

    .line 11
    .line 12
    invoke-virtual {p1}, Lo40/j;->invoke()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    check-cast p1, Ljava/lang/Boolean;

    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    const p3, 0x7f12038c

    .line 23
    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    if-eqz p1, :cond_0

    .line 27
    .line 28
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    check-cast p1, Lq40/i;

    .line 33
    .line 34
    new-instance v3, Lql0/a;

    .line 35
    .line 36
    invoke-direct {v3, v1}, Lql0/a;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    new-array v1, v0, [Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p2, Ljj0/f;

    .line 42
    .line 43
    const v2, 0x7f1202be

    .line 44
    .line 45
    .line 46
    invoke-virtual {p2, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v7

    .line 50
    const v1, 0x7f1202bc

    .line 51
    .line 52
    .line 53
    new-array v2, v0, [Ljava/lang/Object;

    .line 54
    .line 55
    invoke-virtual {p2, v1, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v8

    .line 59
    new-array v0, v0, [Ljava/lang/Object;

    .line 60
    .line 61
    invoke-virtual {p2, p3, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v9

    .line 65
    new-instance v2, Lql0/g;

    .line 66
    .line 67
    const-string v6, ""

    .line 68
    .line 69
    const/16 v10, 0x80

    .line 70
    .line 71
    const/4 v4, 0x0

    .line 72
    const-string v5, ""

    .line 73
    .line 74
    invoke-direct/range {v2 .. v10}, Lql0/g;-><init>(Lql0/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    new-instance p1, Lq40/i;

    .line 81
    .line 82
    invoke-direct {p1, v2}, Lq40/i;-><init>(Lql0/g;)V

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_0
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    check-cast p1, Lq40/i;

    .line 91
    .line 92
    new-instance v3, Lql0/a;

    .line 93
    .line 94
    invoke-direct {v3, v1}, Lql0/a;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    new-array v1, v0, [Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p2, Ljj0/f;

    .line 100
    .line 101
    const v2, 0x7f120e5a

    .line 102
    .line 103
    .line 104
    invoke-virtual {p2, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    const v1, 0x7f120e56

    .line 109
    .line 110
    .line 111
    new-array v2, v0, [Ljava/lang/Object;

    .line 112
    .line 113
    invoke-virtual {p2, v1, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v8

    .line 117
    new-array v0, v0, [Ljava/lang/Object;

    .line 118
    .line 119
    invoke-virtual {p2, p3, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v9

    .line 123
    new-instance v2, Lql0/g;

    .line 124
    .line 125
    const-string v6, ""

    .line 126
    .line 127
    const/16 v10, 0x80

    .line 128
    .line 129
    const/4 v4, 0x0

    .line 130
    const-string v5, ""

    .line 131
    .line 132
    invoke-direct/range {v2 .. v10}, Lql0/g;-><init>(Lql0/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 136
    .line 137
    .line 138
    new-instance p1, Lq40/i;

    .line 139
    .line 140
    invoke-direct {p1, v2}, Lq40/i;-><init>(Lql0/g;)V

    .line 141
    .line 142
    .line 143
    :goto_0
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 144
    .line 145
    .line 146
    return-void
.end method
