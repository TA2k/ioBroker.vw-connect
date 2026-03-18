.class public abstract Lf2/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;

.field public static final b:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Le31/t0;

    .line 2
    .line 3
    const/16 v1, 0x1b

    .line 4
    .line 5
    invoke-direct {v0, v1}, Le31/t0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/u2;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lf2/y;->a:Ll2/u2;

    .line 14
    .line 15
    new-instance v0, Le31/t0;

    .line 16
    .line 17
    const/16 v1, 0x1c

    .line 18
    .line 19
    invoke-direct {v0, v1}, Le31/t0;-><init>(I)V

    .line 20
    .line 21
    .line 22
    new-instance v1, Ll2/e0;

    .line 23
    .line 24
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 25
    .line 26
    .line 27
    sput-object v1, Lf2/y;->b:Ll2/e0;

    .line 28
    .line 29
    return-void
.end method
