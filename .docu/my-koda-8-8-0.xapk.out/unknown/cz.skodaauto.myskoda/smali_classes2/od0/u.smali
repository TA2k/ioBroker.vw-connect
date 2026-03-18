.class public final Lod0/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqd0/y;
.implements Lme0/a;
.implements Lme0/b;


# static fields
.field public static final i:Lrd0/n;


# instance fields
.field public final a:Lve0/u;

.field public b:Ljava/lang/Object;

.field public final c:Lyy0/c2;

.field public final d:Lyy0/l1;

.field public e:Z

.field public final f:Lyy0/c2;

.field public final g:Lyy0/l1;

.field public h:Ljava/time/OffsetDateTime;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lrd0/n;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1}, Lrd0/n;-><init>(Lqr0/a;Lrd0/c0;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lod0/u;->i:Lrd0/n;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lve0/u;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lod0/u;->a:Lve0/u;

    .line 5
    .line 6
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 7
    .line 8
    iput-object p1, p0, Lod0/u;->b:Ljava/lang/Object;

    .line 9
    .line 10
    new-instance p1, Lne0/e;

    .line 11
    .line 12
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    invoke-direct {p1, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iput-object p1, p0, Lod0/u;->c:Lyy0/c2;

    .line 22
    .line 23
    new-instance v0, Lyy0/l1;

    .line 24
    .line 25
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lod0/u;->d:Lyy0/l1;

    .line 29
    .line 30
    sget-object p1, Lod0/u;->i:Lrd0/n;

    .line 31
    .line 32
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iput-object p1, p0, Lod0/u;->f:Lyy0/c2;

    .line 37
    .line 38
    new-instance v0, Lyy0/l1;

    .line 39
    .line 40
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 41
    .line 42
    .line 43
    iput-object v0, p0, Lod0/u;->g:Lyy0/l1;

    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lod0/u;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lod0/u;->f:Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    sget-object v2, Lod0/u;->i:Lrd0/n;

    .line 11
    .line 12
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lod0/u;->a:Lve0/u;

    .line 16
    .line 17
    const-string v0, "PREF_HISTORY_DISCLAIMER"

    .line 18
    .line 19
    invoke-virtual {p0, v0, p1}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 24
    .line 25
    if-ne p0, p1, :cond_0

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0
.end method

.method public final b()V
    .locals 3

    .line 1
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 2
    .line 3
    iput-object v0, p0, Lod0/u;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iget-object v0, p0, Lod0/u;->c:Lyy0/c2;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    sget-object v2, Lne0/d;->a:Lne0/d;

    .line 12
    .line 13
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    iput-object v1, p0, Lod0/u;->h:Ljava/time/OffsetDateTime;

    .line 17
    .line 18
    return-void
.end method
