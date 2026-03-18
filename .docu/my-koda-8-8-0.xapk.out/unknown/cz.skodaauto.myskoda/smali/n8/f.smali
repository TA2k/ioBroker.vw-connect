.class public final Ln8/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ln8/e;

.field public final b:Ln8/e;

.field public final c:I

.field public final d:Z


# direct methods
.method public constructor <init>(Ln8/e;Ln8/e;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln8/f;->a:Ln8/e;

    .line 5
    .line 6
    iput-object p2, p0, Ln8/f;->b:Ln8/e;

    .line 7
    .line 8
    iput p3, p0, Ln8/f;->c:I

    .line 9
    .line 10
    if-ne p1, p2, :cond_0

    .line 11
    .line 12
    const/4 p1, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p1, 0x0

    .line 15
    :goto_0
    iput-boolean p1, p0, Ln8/f;->d:Z

    .line 16
    .line 17
    return-void
.end method
