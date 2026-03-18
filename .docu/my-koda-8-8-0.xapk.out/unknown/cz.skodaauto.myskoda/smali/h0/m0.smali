.class public final Lh0/m0;
.super Ljava/lang/Exception;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:I


# direct methods
.method public constructor <init>(ILjava/lang/IllegalArgumentException;)V
    .locals 1

    .line 1
    const-string v0, "Expected camera missing from device."

    .line 2
    .line 3
    invoke-direct {p0, v0, p2}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 4
    .line 5
    .line 6
    iput p1, p0, Lh0/m0;->d:I

    .line 7
    .line 8
    return-void
.end method
