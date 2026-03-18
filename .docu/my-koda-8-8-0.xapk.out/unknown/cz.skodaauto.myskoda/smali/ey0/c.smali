.class public final Ley0/c;
.super Ley0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Ley0/b;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ley0/b;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Ley0/b;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Ley0/c;->f:Ley0/b;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final f()Ljava/util/Random;
    .locals 1

    .line 1
    iget-object p0, p0, Ley0/c;->f:Ley0/b;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "get(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    check-cast p0, Ljava/util/Random;

    .line 13
    .line 14
    return-object p0
.end method
