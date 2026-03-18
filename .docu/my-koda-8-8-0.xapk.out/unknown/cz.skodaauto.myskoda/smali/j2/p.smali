.class public final Lj2/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lu2/l;


# instance fields
.field public final a:Lc1/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Li91/i0;

    .line 2
    .line 3
    const/16 v1, 0x15

    .line 4
    .line 5
    invoke-direct {v0, v1}, Li91/i0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lim0/b;

    .line 9
    .line 10
    const/16 v2, 0x8

    .line 11
    .line 12
    invoke-direct {v1, v2}, Lim0/b;-><init>(I)V

    .line 13
    .line 14
    .line 15
    new-instance v2, Lu2/l;

    .line 16
    .line 17
    invoke-direct {v2, v0, v1}, Lu2/l;-><init>(Lay0/n;Lay0/k;)V

    .line 18
    .line 19
    .line 20
    sput-object v2, Lj2/p;->b:Lu2/l;

    .line 21
    .line 22
    return-void
.end method

.method public constructor <init>(Lc1/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj2/p;->a:Lc1/c;

    .line 5
    .line 6
    return-void
.end method
