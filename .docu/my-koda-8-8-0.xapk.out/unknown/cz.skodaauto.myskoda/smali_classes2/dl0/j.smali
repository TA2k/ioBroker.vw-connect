.class public abstract Ldl0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lly0/n;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lly0/n;

    .line 2
    .line 3
    sget-object v1, Lly0/o;->d:[Lly0/o;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const-string v2, "(\\D* ?)([\\d.,]+)(\\D*)"

    .line 7
    .line 8
    invoke-direct {v0, v2, v1}, Lly0/n;-><init>(Ljava/lang/String;I)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Ldl0/j;->a:Lly0/n;

    .line 12
    .line 13
    return-void
.end method
