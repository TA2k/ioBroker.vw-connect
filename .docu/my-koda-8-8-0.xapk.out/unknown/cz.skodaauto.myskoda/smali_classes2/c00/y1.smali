.class public final Lc00/y1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lij0/a;

.field public final j:Llb0/z;

.field public final k:Llb0/p;

.field public final l:Lko0/f;

.field public final m:Ljn0/c;

.field public final n:Lqf0/g;

.field public o:Lmb0/l;


# direct methods
.method public constructor <init>(Ltr0/b;Lij0/a;Llb0/z;Llb0/p;Lko0/f;Ljn0/c;Lqf0/g;)V
    .locals 11

    .line 1
    new-instance v0, Lc00/x1;

    .line 2
    .line 3
    sget-object v1, Lc00/v1;->f:Lc00/v1;

    .line 4
    .line 5
    sget-object v5, Lc00/w1;->f:Lc00/w1;

    .line 6
    .line 7
    sget v2, Lmy0/c;->g:I

    .line 8
    .line 9
    const-wide/16 v8, 0x0

    .line 10
    .line 11
    const/4 v10, 0x0

    .line 12
    const/4 v6, 0x0

    .line 13
    const/4 v7, 0x0

    .line 14
    move-object v2, v1

    .line 15
    move-object v3, v1

    .line 16
    move-object v4, v1

    .line 17
    invoke-direct/range {v0 .. v10}, Lc00/x1;-><init>(Lc00/v1;Lc00/v1;Lc00/v1;Lc00/v1;Lc00/w1;ZZJZ)V

    .line 18
    .line 19
    .line 20
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lc00/y1;->h:Ltr0/b;

    .line 24
    .line 25
    iput-object p2, p0, Lc00/y1;->i:Lij0/a;

    .line 26
    .line 27
    iput-object p3, p0, Lc00/y1;->j:Llb0/z;

    .line 28
    .line 29
    iput-object p4, p0, Lc00/y1;->k:Llb0/p;

    .line 30
    .line 31
    move-object/from16 p1, p5

    .line 32
    .line 33
    iput-object p1, p0, Lc00/y1;->l:Lko0/f;

    .line 34
    .line 35
    move-object/from16 p1, p6

    .line 36
    .line 37
    iput-object p1, p0, Lc00/y1;->m:Ljn0/c;

    .line 38
    .line 39
    move-object/from16 p1, p7

    .line 40
    .line 41
    iput-object p1, p0, Lc00/y1;->n:Lqf0/g;

    .line 42
    .line 43
    new-instance p1, Lmb0/l;

    .line 44
    .line 45
    const/4 p2, 0x0

    .line 46
    invoke-direct {p1, p2, p2, p2, p2}, Lmb0/l;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 47
    .line 48
    .line 49
    iput-object p1, p0, Lc00/y1;->o:Lmb0/l;

    .line 50
    .line 51
    new-instance p1, Lc00/u1;

    .line 52
    .line 53
    const/4 p3, 0x0

    .line 54
    invoke-direct {p1, p0, p2, p3}, Lc00/u1;-><init>(Lc00/y1;Lkotlin/coroutines/Continuation;I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 58
    .line 59
    .line 60
    new-instance p1, Lc00/u1;

    .line 61
    .line 62
    const/4 p3, 0x1

    .line 63
    invoke-direct {p1, p0, p2, p3}, Lc00/u1;-><init>(Lc00/y1;Lkotlin/coroutines/Continuation;I)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 67
    .line 68
    .line 69
    return-void
.end method
