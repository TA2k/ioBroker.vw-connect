.class public abstract Ljb/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljb/d;


# instance fields
.field public final a:Lh2/s;


# direct methods
.method public constructor <init>(Lh2/s;)V
    .locals 1

    .line 1
    const-string v0, "tracker"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ljb/b;->a:Lh2/s;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(Leb/e;)Lyy0/c;
    .locals 2

    .line 1
    const-string v0, "constraints"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p1, Lif0/d0;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    const/4 v1, 0x5

    .line 10
    invoke-direct {p1, p0, v0, v1}, Lif0/d0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lyy0/u;->h(Lay0/n;)Lyy0/c;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public abstract c()I
.end method

.method public abstract d(Ljava/lang/Object;)Z
.end method
