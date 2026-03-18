.class public final synthetic Ldx/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(Lc2/k;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p2, p0, Ldx/a;->d:I

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    .line 1
    iget p0, p0, Ldx/a;->d:I

    .line 2
    .line 3
    const-string v0, "$updateType"

    .line 4
    .line 5
    invoke-static {p0, v0}, Lia/b;->q(ILjava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
