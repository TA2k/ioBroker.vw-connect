.class public final synthetic Lw0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk0/a;
.implements Lp/a;


# instance fields
.field public final synthetic d:Lw0/c;


# direct methods
.method public synthetic constructor <init>(Lw0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lw0/b;->d:Lw0/c;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public apply(Ljava/lang/Object;)Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 0

    check-cast p1, Ljava/lang/Void;

    .line 1
    iget-object p0, p0, Lw0/b;->d:Lw0/c;

    iget-object p0, p0, Lw0/c;->d:Landroidx/core/app/a0;

    invoke-virtual {p0}, Landroidx/core/app/a0;->i()Lcom/google/common/util/concurrent/ListenableFuture;

    move-result-object p0

    return-object p0
.end method

.method public apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/lang/Void;

    .line 2
    sget-object p1, Lw0/h;->e:Lw0/h;

    iget-object p0, p0, Lw0/b;->d:Lw0/c;

    invoke-virtual {p0, p1}, Lw0/c;->b(Lw0/h;)V

    const/4 p0, 0x0

    return-object p0
.end method
