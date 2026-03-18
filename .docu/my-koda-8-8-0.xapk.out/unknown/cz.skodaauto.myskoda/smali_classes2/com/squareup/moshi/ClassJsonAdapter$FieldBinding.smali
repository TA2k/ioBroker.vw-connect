.class Lcom/squareup/moshi/ClassJsonAdapter$FieldBinding;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/squareup/moshi/ClassJsonAdapter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "FieldBinding"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/reflect/Field;

.field public final c:Lcom/squareup/moshi/JsonAdapter;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/reflect/Field;Lcom/squareup/moshi/JsonAdapter;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/squareup/moshi/ClassJsonAdapter$FieldBinding;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/squareup/moshi/ClassJsonAdapter$FieldBinding;->b:Ljava/lang/reflect/Field;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/squareup/moshi/ClassJsonAdapter$FieldBinding;->c:Lcom/squareup/moshi/JsonAdapter;

    .line 9
    .line 10
    return-void
.end method
