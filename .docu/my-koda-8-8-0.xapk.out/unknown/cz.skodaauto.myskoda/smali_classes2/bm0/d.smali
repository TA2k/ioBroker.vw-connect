.class public final Lbm0/d;
.super Ljava/lang/RuntimeException;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:I

.field public final e:Lbm0/c;


# direct methods
.method public constructor <init>(ILjava/lang/String;Lbm0/c;)V
    .locals 1

    .line 1
    const-string v0, "message"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, p2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iput p1, p0, Lbm0/d;->d:I

    .line 10
    .line 11
    iput-object p3, p0, Lbm0/d;->e:Lbm0/c;

    .line 12
    .line 13
    return-void
.end method
