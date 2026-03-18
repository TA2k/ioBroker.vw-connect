.class public final Lm30/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo30/i;
.implements Lme0/a;


# instance fields
.field public a:Ljava/lang/String;

.field public final b:Lyy0/c2;

.field public final c:Lyy0/l1;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {v0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    const-string v1, "toString(...)"

    .line 13
    .line 14
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lm30/a;->a:Ljava/lang/String;

    .line 18
    .line 19
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 20
    .line 21
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iput-object v0, p0, Lm30/a;->b:Lyy0/c2;

    .line 26
    .line 27
    new-instance v1, Lyy0/l1;

    .line 28
    .line 29
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 30
    .line 31
    .line 32
    iput-object v1, p0, Lm30/a;->c:Lyy0/l1;

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string p1, ""

    .line 2
    .line 3
    iput-object p1, p0, Lm30/a;->a:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lm30/a;->b:Lyy0/c2;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 12
    .line 13
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    return-object p0
.end method
