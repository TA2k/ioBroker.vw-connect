.class public final Leb/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/concurrent/ExecutorService;

.field public final b:Lcz0/e;

.field public final c:Ljava/util/concurrent/ExecutorService;

.field public final d:Leb/j;

.field public final e:Leb/j;

.field public final f:Leb/j;

.field public final g:Laq/a;

.field public final h:I

.field public final i:I

.field public final j:I

.field public final k:I

.field public final l:Z

.field public final m:Leb/j;


# direct methods
.method public constructor <init>(Leb/j;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x0

    .line 5
    invoke-static {p1}, Lkp/a6;->a(Z)Ljava/util/concurrent/ExecutorService;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iput-object p1, p0, Leb/b;->a:Ljava/util/concurrent/ExecutorService;

    .line 10
    .line 11
    sget-object p1, Lvy0/p0;->a:Lcz0/e;

    .line 12
    .line 13
    iput-object p1, p0, Leb/b;->b:Lcz0/e;

    .line 14
    .line 15
    const/4 p1, 0x1

    .line 16
    invoke-static {p1}, Lkp/a6;->a(Z)Ljava/util/concurrent/ExecutorService;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    iput-object v0, p0, Leb/b;->c:Ljava/util/concurrent/ExecutorService;

    .line 21
    .line 22
    new-instance v0, Leb/j;

    .line 23
    .line 24
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object v0, p0, Leb/b;->d:Leb/j;

    .line 28
    .line 29
    sget-object v0, Leb/j;->a:Leb/j;

    .line 30
    .line 31
    iput-object v0, p0, Leb/b;->e:Leb/j;

    .line 32
    .line 33
    sget-object v0, Leb/j;->b:Leb/j;

    .line 34
    .line 35
    iput-object v0, p0, Leb/b;->f:Leb/j;

    .line 36
    .line 37
    new-instance v0, Laq/a;

    .line 38
    .line 39
    const/16 v1, 0x14

    .line 40
    .line 41
    invoke-direct {v0, v1}, Laq/a;-><init>(I)V

    .line 42
    .line 43
    .line 44
    iput-object v0, p0, Leb/b;->g:Laq/a;

    .line 45
    .line 46
    const/4 v0, 0x4

    .line 47
    iput v0, p0, Leb/b;->h:I

    .line 48
    .line 49
    const v0, 0x7fffffff

    .line 50
    .line 51
    .line 52
    iput v0, p0, Leb/b;->i:I

    .line 53
    .line 54
    const/16 v0, 0x14

    .line 55
    .line 56
    iput v0, p0, Leb/b;->k:I

    .line 57
    .line 58
    const/16 v0, 0x8

    .line 59
    .line 60
    iput v0, p0, Leb/b;->j:I

    .line 61
    .line 62
    iput-boolean p1, p0, Leb/b;->l:Z

    .line 63
    .line 64
    new-instance p1, Leb/j;

    .line 65
    .line 66
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 67
    .line 68
    .line 69
    iput-object p1, p0, Leb/b;->m:Leb/j;

    .line 70
    .line 71
    return-void
.end method
