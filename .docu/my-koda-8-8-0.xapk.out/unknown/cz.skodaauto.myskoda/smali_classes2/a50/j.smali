.class public final La50/j;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lal0/o1;

.field public final i:Luk0/a0;

.field public final j:Lwj0/r;

.field public final k:Ltr0/b;

.field public final l:Lrq0/f;

.field public final m:Lij0/a;


# direct methods
.method public constructor <init>(Lz40/e;Lal0/x0;Lal0/s0;Lz40/c;Lal0/o1;Luk0/a0;Lwj0/r;Ltr0/b;Lrq0/f;Lij0/a;)V
    .locals 7

    .line 1
    new-instance v0, La50/i;

    .line 2
    .line 3
    const/4 v4, 0x0

    .line 4
    const/4 v6, 0x0

    .line 5
    const-string v1, ""

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v5, 0x0

    .line 10
    invoke-direct/range {v0 .. v6}, La50/i;-><init>(Ljava/lang/String;ZLjava/lang/Integer;ZLbl0/h0;Z)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p5, p0, La50/j;->h:Lal0/o1;

    .line 17
    .line 18
    iput-object p6, p0, La50/j;->i:Luk0/a0;

    .line 19
    .line 20
    iput-object p7, p0, La50/j;->j:Lwj0/r;

    .line 21
    .line 22
    iput-object p8, p0, La50/j;->k:Ltr0/b;

    .line 23
    .line 24
    move-object/from16 p5, p9

    .line 25
    .line 26
    iput-object p5, p0, La50/j;->l:Lrq0/f;

    .line 27
    .line 28
    move-object/from16 p5, p10

    .line 29
    .line 30
    iput-object p5, p0, La50/j;->m:Lij0/a;

    .line 31
    .line 32
    new-instance p5, La50/a;

    .line 33
    .line 34
    const/4 p6, 0x0

    .line 35
    const/4 p7, 0x0

    .line 36
    invoke-direct {p5, p1, p7, p6}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, p5}, Lql0/j;->b(Lay0/n;)V

    .line 40
    .line 41
    .line 42
    new-instance p1, La50/c;

    .line 43
    .line 44
    const/4 p5, 0x0

    .line 45
    invoke-direct {p1, p5, p2, p0, p7}, La50/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 49
    .line 50
    .line 51
    new-instance p1, La50/c;

    .line 52
    .line 53
    const/4 p2, 0x1

    .line 54
    invoke-direct {p1, p2, p3, p0, p7}, La50/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 58
    .line 59
    .line 60
    new-instance p1, La50/e;

    .line 61
    .line 62
    const/4 p2, 0x0

    .line 63
    invoke-direct {p1, p0, p7, p2}, La50/e;-><init>(La50/j;Lkotlin/coroutines/Continuation;I)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 67
    .line 68
    .line 69
    new-instance p1, La50/e;

    .line 70
    .line 71
    const/4 p2, 0x1

    .line 72
    invoke-direct {p1, p0, p7, p2}, La50/e;-><init>(La50/j;Lkotlin/coroutines/Continuation;I)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p4}, Lz40/c;->invoke()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    check-cast p1, Lyy0/i;

    .line 83
    .line 84
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-static {p1, p0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 89
    .line 90
    .line 91
    return-void
.end method
