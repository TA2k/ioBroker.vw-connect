.class public final synthetic Lfw0/z0;
.super Lkotlin/jvm/internal/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# static fields
.field public static final d:Lfw0/z0;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lfw0/z0;

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    sget-object v4, Lkotlin/jvm/internal/d;->NO_RECEIVER:Ljava/lang/Object;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const-class v3, Lfw0/y0;

    .line 8
    .line 9
    const-string v5, "<init>"

    .line 10
    .line 11
    const-string v6, "<init>(Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;)V"

    .line 12
    .line 13
    invoke-direct/range {v0 .. v6}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lfw0/z0;->d:Lfw0/z0;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    new-instance p0, Lfw0/y0;

    .line 2
    .line 3
    invoke-direct {p0}, Lfw0/y0;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
