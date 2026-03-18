.class public abstract Lim/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ld8/c;

.field public static final b:Ld8/c;

.field public static final c:Ld8/c;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ld8/c;

    .line 2
    .line 3
    const-string v1, "GET"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lim/h;->a:Ld8/c;

    .line 9
    .line 10
    new-instance v0, Ld8/c;

    .line 11
    .line 12
    sget-object v1, Lim/p;->b:Lim/p;

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lim/h;->b:Ld8/c;

    .line 18
    .line 19
    new-instance v0, Ld8/c;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, v1}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    sput-object v0, Lim/h;->c:Ld8/c;

    .line 26
    .line 27
    return-void
.end method
