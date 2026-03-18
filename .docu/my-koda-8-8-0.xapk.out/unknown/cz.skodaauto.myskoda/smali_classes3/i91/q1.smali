.class public final Li91/q1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Li91/x1;


# instance fields
.field public final a:I

.field public final b:Le3/s;


# direct methods
.method public constructor <init>(ILe3/s;I)V
    .locals 0

    .line 1
    and-int/lit8 p3, p3, 0x4

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    :cond_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput p1, p0, Li91/q1;->a:I

    .line 10
    .line 11
    iput-object p2, p0, Li91/q1;->b:Le3/s;

    .line 12
    .line 13
    return-void
.end method
