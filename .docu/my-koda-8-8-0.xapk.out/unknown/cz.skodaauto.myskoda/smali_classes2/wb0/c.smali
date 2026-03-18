.class public abstract Lwb0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Llx0/q;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lvd/i;

    .line 2
    .line 3
    const/16 v1, 0x18

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lvd/i;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sput-object v0, Lwb0/c;->a:Llx0/q;

    .line 13
    .line 14
    return-void
.end method

.method public static a()Lcom/squareup/moshi/Moshi;
    .locals 2

    .line 1
    sget-object v0, Lwb0/c;->a:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "getValue(...)"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    check-cast v0, Lcom/squareup/moshi/Moshi;

    .line 13
    .line 14
    return-object v0
.end method
