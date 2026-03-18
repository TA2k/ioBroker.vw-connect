.class public final Lx90/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lz90/p;
.implements Lme0/a;
.implements Lme0/b;


# instance fields
.field public final a:Lwe0/a;

.field public final b:Lez0/c;

.field public c:Laa0/j;

.field public final d:Lyy0/c2;

.field public final e:Lyy0/l1;

.field public f:Laa0/d;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/l1;


# direct methods
.method public constructor <init>(Lwe0/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lx90/a;->a:Lwe0/a;

    .line 5
    .line 6
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lx90/a;->b:Lez0/c;

    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iput-object p1, p0, Lx90/a;->d:Lyy0/c2;

    .line 18
    .line 19
    new-instance v0, Lyy0/l1;

    .line 20
    .line 21
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Lx90/a;->e:Lyy0/l1;

    .line 25
    .line 26
    sget-object p1, Lne0/d;->a:Lne0/d;

    .line 27
    .line 28
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iput-object p1, p0, Lx90/a;->g:Lyy0/c2;

    .line 33
    .line 34
    new-instance v0, Lyy0/l1;

    .line 35
    .line 36
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Lx90/a;->h:Lyy0/l1;

    .line 40
    .line 41
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p1, p0, Lx90/a;->a:Lwe0/a;

    .line 2
    .line 3
    check-cast p1, Lwe0/c;

    .line 4
    .line 5
    invoke-virtual {p1}, Lwe0/c;->a()V

    .line 6
    .line 7
    .line 8
    iget-object p1, p0, Lx90/a;->g:Lyy0/c2;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    sget-object v1, Lne0/d;->a:Lne0/d;

    .line 15
    .line 16
    invoke-virtual {p1, v0, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lx90/a;->d:Lyy0/c2;

    .line 20
    .line 21
    invoke-virtual {p0, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    return-object p0
.end method
