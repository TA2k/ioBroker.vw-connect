.class public final Ls70/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lq70/b;

.field public final i:Lq70/f;

.field public final j:Lcs0/c;


# direct methods
.method public constructor <init>(Lq70/b;Lq70/f;Lcs0/c;Lij0/a;)V
    .locals 11

    .line 1
    new-instance v0, Ls70/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ls70/b;-><init>(Lql0/g;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Ls70/c;->h:Lq70/b;

    .line 11
    .line 12
    iput-object p2, p0, Ls70/c;->i:Lq70/f;

    .line 13
    .line 14
    iput-object p3, p0, Ls70/c;->j:Lcs0/c;

    .line 15
    .line 16
    new-instance p1, Ls70/a;

    .line 17
    .line 18
    const/4 p2, 0x0

    .line 19
    invoke-direct {p1, p0, v1, p2}, Ls70/a;-><init>(Ls70/c;Lkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    check-cast p1, Ls70/b;

    .line 30
    .line 31
    new-instance v2, Lql0/g;

    .line 32
    .line 33
    new-instance v3, Lql0/a;

    .line 34
    .line 35
    invoke-direct {v3, v1}, Lql0/a;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 39
    .line 40
    .line 41
    move-result-wide p2

    .line 42
    invoke-static {p2, p3}, Lzo/e;->c(J)Ljava/time/OffsetDateTime;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    invoke-static {p2}, Lvo/a;->l(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    const/4 p2, 0x0

    .line 51
    new-array p3, p2, [Ljava/lang/Object;

    .line 52
    .line 53
    check-cast p4, Ljj0/f;

    .line 54
    .line 55
    const v0, 0x7f1201b4

    .line 56
    .line 57
    .line 58
    invoke-virtual {p4, v0, p3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v7

    .line 62
    const p3, 0x7f1201b3

    .line 63
    .line 64
    .line 65
    new-array v0, p2, [Ljava/lang/Object;

    .line 66
    .line 67
    invoke-virtual {p4, p3, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v8

    .line 71
    const p3, 0x7f12038c

    .line 72
    .line 73
    .line 74
    new-array p2, p2, [Ljava/lang/Object;

    .line 75
    .line 76
    invoke-virtual {p4, p3, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v9

    .line 80
    const/16 v10, 0x80

    .line 81
    .line 82
    const/4 v4, 0x0

    .line 83
    const-string v6, "8.8.0"

    .line 84
    .line 85
    invoke-direct/range {v2 .. v10}, Lql0/g;-><init>(Lql0/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    new-instance p1, Ls70/b;

    .line 92
    .line 93
    invoke-direct {p1, v2}, Ls70/b;-><init>(Lql0/g;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 97
    .line 98
    .line 99
    return-void
.end method
