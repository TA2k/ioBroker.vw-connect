.class public interface abstract Lb0/m1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh0/g0;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lh0/g0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-wide/16 v2, 0x1770

    .line 5
    .line 6
    invoke-direct {v0, v2, v3, v1}, Lh0/g0;-><init>(JI)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lb0/m1;->a:Lh0/g0;

    .line 10
    .line 11
    new-instance v0, Lh0/g0;

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    invoke-direct {v0, v2, v3, v1}, Lh0/g0;-><init>(JI)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public abstract a()J
.end method

.method public abstract b(Lcom/google/crypto/tink/shaded/protobuf/d;)Lb0/l1;
.end method
