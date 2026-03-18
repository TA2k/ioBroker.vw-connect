.class public final Lv90/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lkf0/p;

.field public final j:Lkf0/i;

.field public final k:Lkf0/r;

.field public final l:Lci0/j;

.field public final m:Lqf0/g;

.field public final n:Lij0/a;


# direct methods
.method public constructor <init>(Ltr0/b;Lkf0/p;Lkf0/i;Lkf0/r;Lci0/j;Lqf0/g;Lij0/a;)V
    .locals 6

    .line 1
    new-instance v0, Lv90/a;

    .line 2
    .line 3
    const/4 v4, 0x0

    .line 4
    const/4 v5, 0x0

    .line 5
    const-string v1, ""

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    invoke-direct/range {v0 .. v5}, Lv90/a;-><init>(Ljava/lang/String;Lql0/g;ZZZ)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lv90/b;->h:Ltr0/b;

    .line 16
    .line 17
    iput-object p2, p0, Lv90/b;->i:Lkf0/p;

    .line 18
    .line 19
    iput-object p3, p0, Lv90/b;->j:Lkf0/i;

    .line 20
    .line 21
    iput-object p4, p0, Lv90/b;->k:Lkf0/r;

    .line 22
    .line 23
    iput-object p5, p0, Lv90/b;->l:Lci0/j;

    .line 24
    .line 25
    iput-object p6, p0, Lv90/b;->m:Lqf0/g;

    .line 26
    .line 27
    iput-object p7, p0, Lv90/b;->n:Lij0/a;

    .line 28
    .line 29
    new-instance p1, Ltz/o2;

    .line 30
    .line 31
    const/16 p2, 0x18

    .line 32
    .line 33
    const/4 p3, 0x0

    .line 34
    invoke-direct {p1, p0, p3, p2}, Ltz/o2;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 38
    .line 39
    .line 40
    new-instance p1, Lrp0/a;

    .line 41
    .line 42
    const/16 p2, 0x1b

    .line 43
    .line 44
    invoke-direct {p1, p0, p3, p2}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 48
    .line 49
    .line 50
    return-void
.end method


# virtual methods
.method public final h(Ljava/lang/String;)V
    .locals 8

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    move-object v1, v0

    .line 11
    check-cast v1, Lv90/a;

    .line 12
    .line 13
    iget-object v0, p0, Lv90/b;->k:Lkf0/r;

    .line 14
    .line 15
    invoke-virtual {v0, p1}, Lkf0/r;->a(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    xor-int/lit8 v3, v0, 0x1

    .line 24
    .line 25
    const/4 v6, 0x0

    .line 26
    const/16 v7, 0x1c

    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    const/4 v5, 0x0

    .line 30
    move-object v2, p1

    .line 31
    invoke-static/range {v1 .. v7}, Lv90/a;->a(Lv90/a;Ljava/lang/String;ZZZLql0/g;I)Lv90/a;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method
