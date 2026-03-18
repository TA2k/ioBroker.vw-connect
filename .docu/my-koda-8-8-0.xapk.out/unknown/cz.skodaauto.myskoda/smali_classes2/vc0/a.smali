.class public abstract Lvc0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Le21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lvb/a;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Lvb/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Le21/a;

    .line 8
    .line 9
    invoke-direct {v1}, Le21/a;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, v1}, Lvb/a;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    sput-object v1, Lvc0/a;->a:Le21/a;

    .line 16
    .line 17
    return-void
.end method
