.class public final Lxm0/h;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lvm0/c;

.field public final i:Lvm0/a;

.field public final j:Lkf0/b0;

.field public final k:Lbq0/j;

.field public final l:Ltr0/b;

.field public final m:Lbd0/c;

.field public final n:Lbh0/g;

.field public final o:Lbh0/j;

.field public final p:Lij0/a;


# direct methods
.method public constructor <init>(Lvm0/c;Lvm0/a;Lkf0/b0;Lbq0/j;Ltr0/b;Lbd0/c;Lbh0/g;Lbh0/j;Lij0/a;)V
    .locals 9

    .line 1
    new-instance v0, Lxm0/e;

    .line 2
    .line 3
    const/4 v3, 0x0

    .line 4
    const-string v6, ""

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    const/4 v5, 0x0

    .line 10
    const/4 v7, 0x0

    .line 11
    const/4 v8, 0x0

    .line 12
    invoke-direct/range {v0 .. v8}, Lxm0/e;-><init>(ZZZLwm0/b;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcq0/x;)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lxm0/h;->h:Lvm0/c;

    .line 19
    .line 20
    iput-object p2, p0, Lxm0/h;->i:Lvm0/a;

    .line 21
    .line 22
    iput-object p3, p0, Lxm0/h;->j:Lkf0/b0;

    .line 23
    .line 24
    iput-object p4, p0, Lxm0/h;->k:Lbq0/j;

    .line 25
    .line 26
    iput-object p5, p0, Lxm0/h;->l:Ltr0/b;

    .line 27
    .line 28
    iput-object p6, p0, Lxm0/h;->m:Lbd0/c;

    .line 29
    .line 30
    move-object/from16 p1, p7

    .line 31
    .line 32
    iput-object p1, p0, Lxm0/h;->n:Lbh0/g;

    .line 33
    .line 34
    move-object/from16 p1, p8

    .line 35
    .line 36
    iput-object p1, p0, Lxm0/h;->o:Lbh0/j;

    .line 37
    .line 38
    move-object/from16 p1, p9

    .line 39
    .line 40
    iput-object p1, p0, Lxm0/h;->p:Lij0/a;

    .line 41
    .line 42
    new-instance p1, Lxm0/d;

    .line 43
    .line 44
    const/4 p2, 0x0

    .line 45
    const/4 p3, 0x0

    .line 46
    invoke-direct {p1, p0, p3, p2}, Lxm0/d;-><init>(Lxm0/h;Lkotlin/coroutines/Continuation;I)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 50
    .line 51
    .line 52
    new-instance p1, Lxm0/d;

    .line 53
    .line 54
    const/4 p2, 0x1

    .line 55
    invoke-direct {p1, p0, p3, p2}, Lxm0/d;-><init>(Lxm0/h;Lkotlin/coroutines/Continuation;I)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 59
    .line 60
    .line 61
    return-void
.end method
