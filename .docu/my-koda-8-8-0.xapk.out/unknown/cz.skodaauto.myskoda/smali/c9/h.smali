.class public final Lc9/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public final b:I

.field public final c:Z


# direct methods
.method public constructor <init>(IIZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Lc9/h;->a:I

    .line 3
    iput p2, p0, Lc9/h;->b:I

    .line 4
    iput-boolean p3, p0, Lc9/h;->c:Z

    return-void
.end method

.method public constructor <init>(IZI)V
    .locals 0

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iput p1, p0, Lc9/h;->a:I

    .line 7
    iput-boolean p2, p0, Lc9/h;->c:Z

    .line 8
    iput p3, p0, Lc9/h;->b:I

    return-void
.end method

.method public static a(I)Lc9/h;
    .locals 3

    .line 1
    new-instance v0, Lc9/h;

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, p0, v1, v2}, Lc9/h;-><init>(IIZ)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method
