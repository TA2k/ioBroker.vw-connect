.class public final Ltz/u0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lqd0/q;

.field public final i:Ltr0/b;

.field public final j:Lqd0/s;

.field public final k:Lqd0/w0;

.field public final l:Lqd0/b1;

.field public final m:Lij0/a;

.field public n:Lrd0/d;


# direct methods
.method public constructor <init>(Lqd0/q0;Lqd0/q;Ltr0/b;Lqd0/s;Lqd0/w0;Lqd0/b1;Lij0/a;)V
    .locals 10

    .line 1
    new-instance v0, Ltz/r0;

    .line 2
    .line 3
    const/4 v6, 0x0

    .line 4
    const/4 v8, 0x0

    .line 5
    const/4 v1, 0x0

    .line 6
    const-string v2, ""

    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    const/4 v5, 0x0

    .line 10
    const/4 v7, 0x0

    .line 11
    const/4 v9, 0x0

    .line 12
    move-object v3, v2

    .line 13
    invoke-direct/range {v0 .. v9}, Ltz/r0;-><init>(Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLtz/q0;ZLql0/g;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 17
    .line 18
    .line 19
    iput-object p2, p0, Ltz/u0;->h:Lqd0/q;

    .line 20
    .line 21
    iput-object p3, p0, Ltz/u0;->i:Ltr0/b;

    .line 22
    .line 23
    iput-object p4, p0, Ltz/u0;->j:Lqd0/s;

    .line 24
    .line 25
    iput-object p5, p0, Ltz/u0;->k:Lqd0/w0;

    .line 26
    .line 27
    move-object/from16 p2, p6

    .line 28
    .line 29
    iput-object p2, p0, Ltz/u0;->l:Lqd0/b1;

    .line 30
    .line 31
    move-object/from16 p2, p7

    .line 32
    .line 33
    iput-object p2, p0, Ltz/u0;->m:Lij0/a;

    .line 34
    .line 35
    new-instance p2, Lr60/t;

    .line 36
    .line 37
    const/4 p3, 0x0

    .line 38
    const/16 p4, 0x14

    .line 39
    .line 40
    invoke-direct {p2, p4, p1, p0, p3}, Lr60/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method


# virtual methods
.method public final h(Lrd0/e;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_1

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-ne p1, v0, :cond_0

    .line 9
    .line 10
    const p1, 0x7f120e7d

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance p0, La8/r0;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 17
    .line 18
    .line 19
    throw p0

    .line 20
    :cond_1
    const p1, 0x7f120e84

    .line 21
    .line 22
    .line 23
    :goto_0
    const/4 v0, 0x0

    .line 24
    new-array v0, v0, [Ljava/lang/Object;

    .line 25
    .line 26
    iget-object p0, p0, Ltz/u0;->m:Lij0/a;

    .line 27
    .line 28
    check-cast p0, Ljj0/f;

    .line 29
    .line 30
    invoke-virtual {p0, p1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
