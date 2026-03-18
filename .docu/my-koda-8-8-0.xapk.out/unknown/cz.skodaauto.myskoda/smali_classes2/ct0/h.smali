.class public final Lct0/h;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;

.field public final i:Lat0/a;

.field public final j:Lat0/d;

.field public final k:Lat0/l;

.field public final l:Lat0/h;

.field public final m:Lpg0/c;

.field public final n:Lat0/g;

.field public final o:Lat0/n;

.field public final p:Lat0/i;


# direct methods
.method public constructor <init>(Lij0/a;Lat0/a;Lat0/d;Lat0/l;Lat0/h;Lpg0/c;Lat0/g;Lat0/n;Lat0/i;)V
    .locals 6

    .line 1
    new-instance v0, Lct0/g;

    .line 2
    .line 3
    sget-object v1, Lbt0/b;->e:Lbt0/b;

    .line 4
    .line 5
    const/16 v2, 0x1f

    .line 6
    .line 7
    and-int/lit8 v3, v2, 0x4

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v3, 0x1

    .line 14
    :goto_0
    and-int/lit8 v2, v2, 0x8

    .line 15
    .line 16
    if-eqz v2, :cond_1

    .line 17
    .line 18
    sget-object v1, Lbt0/b;->d:Lbt0/b;

    .line 19
    .line 20
    :cond_1
    move-object v4, v1

    .line 21
    const/4 v1, 0x0

    .line 22
    const/4 v2, 0x0

    .line 23
    const/4 v5, 0x0

    .line 24
    invoke-direct/range {v0 .. v5}, Lct0/g;-><init>(ZZZLbt0/b;Lct0/f;)V

    .line 25
    .line 26
    .line 27
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Lct0/h;->h:Lij0/a;

    .line 31
    .line 32
    iput-object p2, p0, Lct0/h;->i:Lat0/a;

    .line 33
    .line 34
    iput-object p3, p0, Lct0/h;->j:Lat0/d;

    .line 35
    .line 36
    iput-object p4, p0, Lct0/h;->k:Lat0/l;

    .line 37
    .line 38
    iput-object p5, p0, Lct0/h;->l:Lat0/h;

    .line 39
    .line 40
    iput-object p6, p0, Lct0/h;->m:Lpg0/c;

    .line 41
    .line 42
    iput-object p7, p0, Lct0/h;->n:Lat0/g;

    .line 43
    .line 44
    iput-object p8, p0, Lct0/h;->o:Lat0/n;

    .line 45
    .line 46
    iput-object p9, p0, Lct0/h;->p:Lat0/i;

    .line 47
    .line 48
    new-instance p1, Lct0/b;

    .line 49
    .line 50
    const/4 p2, 0x0

    .line 51
    const/4 p3, 0x0

    .line 52
    invoke-direct {p1, p0, p3, p2}, Lct0/b;-><init>(Lct0/h;Lkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 56
    .line 57
    .line 58
    new-instance p1, Lct0/b;

    .line 59
    .line 60
    const/4 p2, 0x1

    .line 61
    invoke-direct {p1, p0, p3, p2}, Lct0/b;-><init>(Lct0/h;Lkotlin/coroutines/Continuation;I)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 65
    .line 66
    .line 67
    new-instance p1, Lct0/b;

    .line 68
    .line 69
    const/4 p2, 0x2

    .line 70
    invoke-direct {p1, p0, p3, p2}, Lct0/b;-><init>(Lct0/h;Lkotlin/coroutines/Continuation;I)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 74
    .line 75
    .line 76
    new-instance p1, Lc80/l;

    .line 77
    .line 78
    const/16 p2, 0x11

    .line 79
    .line 80
    invoke-direct {p1, p0, p3, p2}, Lc80/l;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 84
    .line 85
    .line 86
    return-void
.end method
