.class public final Lba0/v;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lz90/c;

.field public final i:Ltr0/b;

.field public final j:Lz90/u;

.field public final k:Lz90/v;

.field public final l:Lz90/w;

.field public final m:Lz90/j;

.field public final n:Lij0/a;

.field public final o:Lz90/s;

.field public final p:Lz90/q;

.field public final q:Lkf0/v;


# direct methods
.method public constructor <init>(Lz90/c;Ltr0/b;Lz90/u;Lz90/v;Lz90/w;Lz90/j;Lij0/a;Lz90/s;Lz90/q;Lkf0/v;)V
    .locals 8

    .line 1
    new-instance v0, Lba0/u;

    .line 2
    .line 3
    sget-object v1, Llf0/i;->j:Llf0/i;

    .line 4
    .line 5
    sget-object v2, Ler0/g;->d:Ler0/g;

    .line 6
    .line 7
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 8
    .line 9
    const/4 v7, 0x0

    .line 10
    const/4 v3, 0x0

    .line 11
    const/4 v4, 0x1

    .line 12
    const/4 v5, 0x0

    .line 13
    invoke-direct/range {v0 .. v7}, Lba0/u;-><init>(Llf0/i;Ler0/g;Laa0/c;ZLql0/g;Ljava/util/List;Z)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lba0/v;->h:Lz90/c;

    .line 20
    .line 21
    iput-object p2, p0, Lba0/v;->i:Ltr0/b;

    .line 22
    .line 23
    iput-object p3, p0, Lba0/v;->j:Lz90/u;

    .line 24
    .line 25
    iput-object p4, p0, Lba0/v;->k:Lz90/v;

    .line 26
    .line 27
    iput-object p5, p0, Lba0/v;->l:Lz90/w;

    .line 28
    .line 29
    iput-object p6, p0, Lba0/v;->m:Lz90/j;

    .line 30
    .line 31
    iput-object p7, p0, Lba0/v;->n:Lij0/a;

    .line 32
    .line 33
    move-object/from16 p1, p8

    .line 34
    .line 35
    iput-object p1, p0, Lba0/v;->o:Lz90/s;

    .line 36
    .line 37
    move-object/from16 p1, p9

    .line 38
    .line 39
    iput-object p1, p0, Lba0/v;->p:Lz90/q;

    .line 40
    .line 41
    move-object/from16 p1, p10

    .line 42
    .line 43
    iput-object p1, p0, Lba0/v;->q:Lkf0/v;

    .line 44
    .line 45
    new-instance p1, Lba0/s;

    .line 46
    .line 47
    const/4 p2, 0x0

    .line 48
    const/4 p3, 0x0

    .line 49
    invoke-direct {p1, p0, p2, p3}, Lba0/s;-><init>(Lba0/v;Lkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 53
    .line 54
    .line 55
    return-void
.end method

.method public static final h(Lba0/v;Lss0/b;)V
    .locals 10

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object v1, v0

    .line 6
    check-cast v1, Lba0/u;

    .line 7
    .line 8
    sget-object v0, Lss0/e;->S1:Lss0/e;

    .line 9
    .line 10
    invoke-static {p1, v0}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-static {p1, v0}, Lkp/u6;->d(Lss0/b;Lss0/e;)Ler0/g;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    const/4 v8, 0x0

    .line 19
    const/16 v9, 0x74

    .line 20
    .line 21
    const/4 v4, 0x0

    .line 22
    const/4 v5, 0x0

    .line 23
    const/4 v6, 0x0

    .line 24
    const/4 v7, 0x0

    .line 25
    invoke-static/range {v1 .. v9}, Lba0/u;->a(Lba0/u;Llf0/i;Ler0/g;Laa0/c;ZLql0/g;Ljava/util/List;ZI)Lba0/u;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method
