.class public final Lyk0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lal0/a0;
.implements Lme0/a;


# instance fields
.field public final a:Lyy0/c2;

.field public final b:Lyy0/l1;

.field public final c:Lyy0/c2;

.field public final d:Lyy0/l1;

.field public e:Ljava/util/UUID;

.field public final f:Lyy0/c2;

.field public final g:Lyy0/l1;


# direct methods
.method public constructor <init>()V
    .locals 8

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iput-object v0, p0, Lyk0/b;->a:Lyy0/c2;

    .line 10
    .line 11
    new-instance v1, Lyy0/l1;

    .line 12
    .line 13
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 14
    .line 15
    .line 16
    iput-object v1, p0, Lyk0/b;->b:Lyy0/l1;

    .line 17
    .line 18
    new-instance v2, Lne0/c;

    .line 19
    .line 20
    new-instance v3, Lbl0/k;

    .line 21
    .line 22
    invoke-direct {v3}, Lbl0/k;-><init>()V

    .line 23
    .line 24
    .line 25
    const/4 v6, 0x0

    .line 26
    const/16 v7, 0x1e

    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    const/4 v5, 0x0

    .line 30
    invoke-direct/range {v2 .. v7}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 31
    .line 32
    .line 33
    invoke-static {v2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    iput-object v0, p0, Lyk0/b;->c:Lyy0/c2;

    .line 38
    .line 39
    new-instance v1, Lyy0/l1;

    .line 40
    .line 41
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 42
    .line 43
    .line 44
    iput-object v1, p0, Lyk0/b;->d:Lyy0/l1;

    .line 45
    .line 46
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 47
    .line 48
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    iput-object v0, p0, Lyk0/b;->f:Lyy0/c2;

    .line 53
    .line 54
    new-instance v1, Lyy0/l1;

    .line 55
    .line 56
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 57
    .line 58
    .line 59
    iput-object v1, p0, Lyk0/b;->g:Lyy0/l1;

    .line 60
    .line 61
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    const/4 p1, 0x0

    .line 2
    iput-object p1, p0, Lyk0/b;->e:Ljava/util/UUID;

    .line 3
    .line 4
    iget-object v0, p0, Lyk0/b;->a:Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lne0/c;

    .line 10
    .line 11
    new-instance v2, Lbl0/k;

    .line 12
    .line 13
    invoke-direct {v2}, Lbl0/k;-><init>()V

    .line 14
    .line 15
    .line 16
    const/4 v5, 0x0

    .line 17
    const/16 v6, 0x1e

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    const/4 v4, 0x0

    .line 21
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, v1}, Lyk0/b;->b(Lne0/s;)V

    .line 25
    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0
.end method

.method public final b(Lne0/s;)V
    .locals 1

    .line 1
    const-string v0, "place"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lyk0/b;->c:Lyy0/c2;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    return-void
.end method
