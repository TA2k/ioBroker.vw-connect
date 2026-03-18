.class public abstract Lft0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Le21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lf31/n;

    .line 2
    .line 3
    const/16 v1, 0x15

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lf31/n;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Le21/a;

    .line 9
    .line 10
    invoke-direct {v1}, Le21/a;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, v1}, Lf31/n;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    sput-object v1, Lft0/a;->a:Le21/a;

    .line 17
    .line 18
    return-void
.end method
