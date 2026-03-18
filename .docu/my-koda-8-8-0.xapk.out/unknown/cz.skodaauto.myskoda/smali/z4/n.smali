.class public final Lz4/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lb81/d;

.field public final b:Lb81/d;

.field public final c:Lb81/d;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lb81/d;

    .line 5
    .line 6
    const-string v1, "base"

    .line 7
    .line 8
    const/16 v2, 0x1d

    .line 9
    .line 10
    invoke-direct {v0, v2, p1, v1}, Lb81/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lz4/n;->a:Lb81/d;

    .line 14
    .line 15
    new-instance p1, Lb81/d;

    .line 16
    .line 17
    const-string v0, "min"

    .line 18
    .line 19
    const/16 v1, 0x1d

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    invoke-direct {p1, v1, v2, v0}, Lb81/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lz4/n;->b:Lb81/d;

    .line 26
    .line 27
    new-instance p1, Lb81/d;

    .line 28
    .line 29
    const-string v0, "max"

    .line 30
    .line 31
    invoke-direct {p1, v1, v2, v0}, Lb81/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Lz4/n;->c:Lb81/d;

    .line 35
    .line 36
    return-void
.end method
