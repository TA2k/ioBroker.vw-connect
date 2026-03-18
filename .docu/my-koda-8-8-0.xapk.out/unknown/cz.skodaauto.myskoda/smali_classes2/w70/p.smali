.class public final Lw70/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbq0/h;


# direct methods
.method public constructor <init>(Lbq0/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/p;->a:Lbq0/h;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object p0, p0, Lw70/p;->a:Lbq0/h;

    .line 2
    .line 3
    check-cast p0, Lzp0/c;

    .line 4
    .line 5
    iget-object p0, p0, Lzp0/c;->i:Ljava/util/List;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    new-instance v0, Lne0/e;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    return-object v0

    .line 15
    :cond_0
    new-instance v1, Lne0/c;

    .line 16
    .line 17
    new-instance v2, Ljava/lang/IllegalStateException;

    .line 18
    .line 19
    const-string p0, "Booking history is not available"

    .line 20
    .line 21
    invoke-direct {v2, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const/4 v5, 0x0

    .line 25
    const/16 v6, 0x1e

    .line 26
    .line 27
    const/4 v3, 0x0

    .line 28
    const/4 v4, 0x0

    .line 29
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 30
    .line 31
    .line 32
    return-object v1
.end method
