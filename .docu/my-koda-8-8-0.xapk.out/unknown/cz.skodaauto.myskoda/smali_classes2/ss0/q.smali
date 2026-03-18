.class public final Lss0/q;
.super Ljava/lang/Exception;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lss0/q;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lss0/q;

    .line 2
    .line 3
    const-string v1, "Initial vehicle not found"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lss0/q;->d:Lss0/q;

    .line 9
    .line 10
    return-void
.end method
