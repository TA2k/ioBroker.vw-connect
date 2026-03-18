.class public abstract Lhz0/c2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljz0/l;

.field public static final b:Ljz0/u;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    new-instance v0, Ljz0/l;

    .line 2
    .line 3
    new-instance v1, Ljz0/r;

    .line 4
    .line 5
    sget-object v2, Lhz0/b2;->d:Lhz0/b2;

    .line 6
    .line 7
    invoke-interface {v2}, Lhy0/c;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    invoke-direct {v1, v2, v3}, Ljz0/r;-><init>(Lhy0/l;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    const/16 v3, 0xe

    .line 16
    .line 17
    invoke-direct {v0, v1, v2, v3}, Ljz0/l;-><init>(Ljz0/r;Liz0/a;I)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lhz0/c2;->a:Ljz0/l;

    .line 21
    .line 22
    new-instance v4, Ljz0/u;

    .line 23
    .line 24
    new-instance v5, Ljz0/r;

    .line 25
    .line 26
    sget-object v0, Lhz0/a2;->d:Lhz0/a2;

    .line 27
    .line 28
    invoke-interface {v0}, Lhy0/c;->getName()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    invoke-direct {v5, v0, v1}, Ljz0/r;-><init>(Lhy0/l;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    const/4 v8, 0x0

    .line 36
    const/16 v9, 0x38

    .line 37
    .line 38
    const/4 v6, 0x1

    .line 39
    const/16 v7, 0xc

    .line 40
    .line 41
    invoke-direct/range {v4 .. v9}, Ljz0/u;-><init>(Ljz0/r;IILhz0/d1;I)V

    .line 42
    .line 43
    .line 44
    sput-object v4, Lhz0/c2;->b:Ljz0/u;

    .line 45
    .line 46
    return-void
.end method
