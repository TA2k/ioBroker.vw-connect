.class public final Lll/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lu01/k;

.field public final b:Lll/d;


# direct methods
.method public constructor <init>(JLu01/k;Lu01/y;Lvy0/x;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lll/f;->a:Lu01/k;

    .line 5
    .line 6
    new-instance v0, Lll/d;

    .line 7
    .line 8
    move-wide v1, p1

    .line 9
    move-object v3, p3

    .line 10
    move-object v4, p4

    .line 11
    move-object v5, p5

    .line 12
    invoke-direct/range {v0 .. v5}, Lll/d;-><init>(JLu01/k;Lu01/y;Lvy0/x;)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lll/f;->b:Lll/d;

    .line 16
    .line 17
    return-void
.end method
