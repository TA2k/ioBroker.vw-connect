.class public abstract Los/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lbu/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lbt/d;

    .line 2
    .line 3
    invoke-direct {v0}, Lbt/d;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v1, Los/a;->a:Los/a;

    .line 7
    .line 8
    const-class v2, Los/n;

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lbt/d;->a(Ljava/lang/Class;Lzs/d;)Lat/a;

    .line 11
    .line 12
    .line 13
    const-class v2, Los/b;

    .line 14
    .line 15
    invoke-virtual {v0, v2, v1}, Lbt/d;->a(Ljava/lang/Class;Lzs/d;)Lat/a;

    .line 16
    .line 17
    .line 18
    new-instance v1, Lbu/c;

    .line 19
    .line 20
    const/4 v2, 0x6

    .line 21
    invoke-direct {v1, v0, v2}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 22
    .line 23
    .line 24
    sput-object v1, Los/n;->a:Lbu/c;

    .line 25
    .line 26
    return-void
.end method
